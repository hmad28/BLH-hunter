from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..shared import normalize_domain
from ..blh.scanner import PLATFORM_DOMAINS
from ..bac.scanner import BAC_SERVICES
from ..cred.scanner import CRED_CATEGORIES


class ScanConfig(BaseModel):
    model_config = ConfigDict(extra='forbid')
    domain: str
    platforms: list[str] = Field(default_factory=lambda: ["github", "instagram"])
    services: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    providers: list[Literal["sitemap", "wayback", "commoncrawl", "subfinder", "gau", "katana"]] = Field(
        default_factory=lambda: ["sitemap", "wayback", "commoncrawl"])
    engine: Literal["native", "crawlee"] = "crawlee"
    prober: Literal["none", "native", "pd-httpx"] = "native"
    browser: bool = False
    js_analysis: bool = False
    secret_signals: bool = False
    exposure_validation: bool = False
    max_pages: int = Field(default=500, ge=1, le=20000)
    max_urls: int = Field(default=10000, ge=10, le=100000)
    max_depth: int = Field(default=4, ge=0, le=20)
    browser_budget: int = Field(default=20, ge=0, le=500)
    per_host_delay: float = Field(default=1, ge=0.2, le=60)

    @field_validator("domain")
    @classmethod
    def domain_valid(cls, value):
        return normalize_domain(value)

    @model_validator(mode="after")
    def selections(self):
        for field, allowed in (("platforms", PLATFORM_DOMAINS), ("services", BAC_SERVICES),
                               ("categories", CRED_CATEGORIES)):
            values = sorted(set(getattr(self, field)))
            if set(values) - set(allowed):
                raise ValueError(f"Unknown {field}: {', '.join(set(values) - set(allowed))}")
            setattr(self, field, values)
        if not (self.platforms or self.services or self.categories or self.secret_signals):
            raise ValueError("Select at least one platform, service, or exposure category")
        self.providers = list(dict.fromkeys(self.providers))
        if "gau" in self.providers and {"wayback", "commoncrawl"} & set(self.providers):
            raise ValueError("Choose gau OR native archive providers to avoid duplicate archive requests")
        return self

    def coverage(self):
        return sorted([f"blh:{p}" for p in self.platforms] + [f"bac:{p}" for p in self.services]
                      + [f"cred:{p}" for p in self.categories]
                      + (["content:jsluice"] if self.js_analysis else [])
                      + (["content:gitleaks"] if self.secret_signals else [])
                      + (["render:browser"] if self.browser else []))
