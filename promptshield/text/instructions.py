"""A cheap check for text addressed to an AI, as opposed to text about one.

This is a weak signal. It matches phrases, so it misses paraphrases and hits ordinary sentences that
share them: a test on wording nobody tuned for noticed 0 of 12 attacks and flagged 8 of 10 awkward
benign lines (D044). So a hit is only ever supporting evidence. The classifier in L1 does the real
work. Don't grow this list to chase test cases, because that only makes the numbers look better.
"""

import re

_AI = r"(?:ai|llm|language model|chatbot|agent|assistant)s?"
_PRIOR = (
    r"(?:all\s+|any\s+|the\s+|your\s+|my\s+)*(?:previous|prior|above|earlier|preceding|user'?s?)"
)
_ORDERS = r"(?:instructions?|prompts?|requests?|rules?|directions?|messages?|tasks?|guidelines?)"
_VERBS = r"(?:tell|mention|inform|reveal|show|alert|notify|warn)"

INSTRUCTION_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    for pattern in (
        # English
        rf"\b(?:ignore|disregard|forget|override|bypass)\s+{_PRIOR}(?:\s+\w+)?\s+{_ORDERS}",
        rf"\b(?:ignore|disregard|forget)\s+(?:all|everything|any)\b.{{0,40}}{_ORDERS}",
        r"\byou are now\b|\bfrom now on,? you\b|\byour new (?:task|role|instructions?)\b",
        r"\bnew instructions?\b\s*[:\-]|\bsystem prompt\b|^\s*system\s*:",
        rf"\b{_AI}\s+(?:must|should|shall|need to|are required to)\b",
        rf"\b(?:note|message|notice|instructions?|attention)\s+(?:for|to)\s+(?:all\s+|any\s+)?"
        rf"(?:the\s+)?{_AI}\b",
        rf"^\s*(?:dear\s+)?{_AI}\s*[:,]",
        rf"\b(?:do not|don'?t|never|without)\s+{_VERBS}(?:ing)?\s+(?:this\s+|it\s+)?(?:to\s+)?"
        r"(?:the\s+)?user\b",
        r"\bbefore (?:you\s+)?(?:answer|respond|reply|continu|proceed)",
        r"\b(?:use|call|invoke|run)\s+the\s+[\w.-]+\s+(?:tool|function)\b",
        r"\b(?:send|post|upload|forward|email|exfiltrate)\b.{0,80}\bto\s+(?:https?://|\S+@\S+)",
        # Spanish, French, German, Portuguese, Italian
        r"\bignora\s+(?:todas\s+)?(?:las\s+)?instrucciones\b",
        r"\bignore[zr]?\s+(?:toutes\s+)?(?:les\s+)?instructions\b",
        r"\bignoriere?\s+(?:alle\s+)?(?:vorherigen\s+|bisherigen\s+)?anweisungen\b",
        r"\bignore\s+(?:todas\s+)?(?:as\s+)?instruções\b",
        r"\bignora\s+(?:tutte\s+)?(?:le\s+)?istruzioni\b",
        # Chinese, Japanese, Russian
        r"忽略.{0,8}(?:指令|指示|提示)",
        r"(?:指示|命令).{0,8}(?:無視|むし)",
        r"игнорируй(?:те)?\s+(?:все\s+)?(?:предыдущие\s+)?инструкции",
        # Hindi
        r"(?:एआई|ए\.आई\.|AI)\s+सहायक",
        r"(?:निर्देश|निर्देशों)\s*(?:को)?\s*(?:अनदेखा|नज़रअंदाज़|नजरअंदाज)",
        r"उपयोगकर्ता\s+को\s+.{0,40}न\s+(?:बताएं|बताना|बताओ)",
        # Arabic
        r"تجاهل\s+.{0,30}(?:التعليمات|الأوامر)",
        r"(?:لمساعدي|مساعدي|لمساعد)\s+الذكاء\s+الاصطناعي",
        r"(?:لا\s+تخبر|لا\s+تذكر)\s+(?:ال)?مستخدم",
        # A tool named outright, in a script that has its own word for "tool"
        r"\b[a-z]+_[a-z_]+\s+(?:टूल|ツール|工具)",
        r"أداة\s+[a-z]+_[a-z_]+",
    )
)


def count_instruction_signals(text: str) -> int:
    """How many different patterns match. More patterns means more likely a real instruction."""
    return sum(pattern.search(text) is not None for pattern in INSTRUCTION_PATTERNS)
