"""
GenAI module for generating editorial incident reports.

Uses the google-genai SDK to generate a calm, luxury-concierge incident report.
Falls back to a polished procedural template if the API key is missing or calls fail.
"""

import concurrent.futures
import logging
import os
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("agency.genai")

DEFAULT_MODEL = "gemini-2.5-flash"


def build_fallback_report(
    incident: Dict[str, Any],
    plan: Any,
    probability: float
) -> str:
    """
    Construct a pristine, 3-paragraph editorial incident report from raw facts.
    Polite, calm, understated tone of a luxury concierge firm.
    Guaranteed to include attack_type, src_ip, and probability percentage.
    """
    attack_type = incident.get("attack_type", "DDoS")
    src_ip = incident.get("src_ip", "203.0.113.99")
    city = incident.get("origin_city")
    country = incident.get("origin_country")
    ts_str = incident.get("ts", "")

    formatted_time = "earlier today"
    if ts_str:
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            formatted_time = dt.strftime("%I:%M %p").lstrip("0")
        except Exception:
            formatted_time = ts_str

    prob_pct = round(probability * 100) if probability is not None else 95

    # Extract step descriptions if available
    steps_list = []
    if isinstance(plan, dict) and "steps" in plan:
        steps_list = plan["steps"]
    elif isinstance(plan, list):
        steps_list = plan

    if steps_list:
        step_texts = [s.get("description", str(s)) for s in steps_list if isinstance(s, dict)]
        actions_taken = "; ".join(step_texts)
    else:
        actions_taken = f"identifying the ingress origin, adding a targeted firewall rule, and verifying packet cessation for {src_ip}"

    location_clause = f" originating from {city}, {country} ({src_ip})" if city and country else f" from {src_ip}"

    p1 = (
        f"At {formatted_time}, our perimeter monitoring observed an unannounced surge of {attack_type} "
        f"traffic directed at gateway services{location_clause}. Our Bayesian analytical model established "
        f"a malicious probability of {prob_pct}%, prompting immediate tactical staging while estate "
        f"operations continued without interruption."
    )

    p2 = (
        f"In accordance with our quiet protocol, autonomous containment was executed smoothly: {actions_taken}. "
        f"The hostile ingress route was isolated at the boundary before payload transmission could degrade "
        f"resident communications or disturb the sanctuary."
    )

    p3 = (
        f"The estate network has resumed its customary serenity, and all metrics confirm baseline tranquility. "
        f"As our primary operational recommendation, we advise preserving the active firewall restriction on {src_ip} "
        f"while seasonal behavioral monitoring remains continuously engaged."
    )

    return f"{p1}\n\n{p2}\n\n{p3}"


def _call_gemini_api(api_key: str, model_name: str, prompt: str, timeout_seconds: float = 15.0) -> Optional[str]:
    """Execute Gemini API generation in a background thread with an enforced timeout."""
    def _worker():
        from google import genai
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=model_name,
            contents=prompt,
        )
        return response.text if response and response.text else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_worker)
        return future.result(timeout=timeout_seconds)


def write_report(
    incident: Optional[Dict[str, Any]] = None,
    plan: Any = None,
    probability: Optional[float] = None,
    api_key: Optional[str] = None,
    model_name: Optional[str] = None
) -> Tuple[str, str]:
    """
    Generate an incident report in the polite, calm tone of a luxury concierge firm.

    Returns:
        (report_text, generated_by) where generated_by is "gemini" or "fallback".
    """
    incident = incident or {}
    prob = probability if probability is not None else incident.get("probability", 0.95)
    key = api_key if api_key is not None else os.getenv("GEMINI_API_KEY", "").strip()
    model = model_name if model_name is not None else os.getenv("GEMINI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL

    # If key is missing or blank, immediately use fallback template
    if not key:
        logger.info("GEMINI_API_KEY not configured; generating fallback template report.")
        return build_fallback_report(incident, plan, prob), "fallback"

    attack_type = incident.get("attack_type", "DDoS")
    src_ip = incident.get("src_ip", "203.0.113.99")
    city = incident.get("origin_city")
    country = incident.get("origin_country")
    ts_str = incident.get("ts", "")
    prob_pct = round(prob * 100)

    steps_list = []
    if isinstance(plan, dict) and "steps" in plan:
        steps_list = plan["steps"]
    elif isinstance(plan, list):
        steps_list = plan

    if steps_list:
        step_texts = [s.get("description", str(s)) for s in steps_list if isinstance(s, dict)]
        actions_taken = "; ".join(step_texts)
    else:
        actions_taken = f"identified {src_ip}, added firewall rule, verified cessation"

    location_line = f"- Attacker location: {city}, {country}\n" if city and country else ""

    prompt = f"""You are the private cyber concierge for an ultra-luxury nature retreat and security agency.
Write an incident report of approximately 120-180 words in the polite, calm, understated tone of a luxury concierge firm.

Use ONLY the following factual details and do not invent other facts:
- Incident time: {ts_str or 'recently'}
- Attack classification: {attack_type}
- Attacker source IP: {src_ip}
{location_line}- Threat probability: {prob_pct}%
- Tactical actions taken: {actions_taken}
- Current status: Threat blocked and isolated, estate network returned to calm
- Recommendation: Maintain firewall block on {src_ip} and monitor baselines

Requirements:
- Exactly 2 to 3 plain text paragraphs.
- Plain paragraphs ONLY. Absolutely no markdown symbols, no bullet points, no asterisks, no hashtags, and no jargon overload.
- Must include the time, attack type, source IP, probability (as a percentage), actions taken, current status, and ONE recommendation.
{f"- Mention that the attack originated from {city}, {country}." if city and country else ""}
- Tone example: "At 2:00 PM, a DDoS attack was detected. The source IP has been blocked."
"""

    try:
        raw_text = _call_gemini_api(api_key=key, model_name=model, prompt=prompt, timeout_seconds=15.0)
        if raw_text and raw_text.strip():
            # Clean any stray markdown formatting if model accidentally included it
            clean_text = raw_text.replace("**", "").replace("##", "").replace("* ", "").strip()
            return clean_text, "gemini"
        else:
            logger.warning("Gemini returned empty response; switching to fallback template.")
            return build_fallback_report(incident, plan, prob), "fallback"
    except Exception as exc:
        # Never log the API key
        logger.error(f"Gemini report generation failed: {type(exc).__name__}: {exc}")
        return build_fallback_report(incident, plan, prob), "fallback"
