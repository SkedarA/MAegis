import argparse
import asyncio
import hashlib
import ipaddress
import json
import socket
from pathlib import Path
from urllib.parse import urlsplit

ALLOWED_PORTS = {None, 80, 443}
MAX_REQUESTS = 120
MAX_BODY_BYTES = 5_000_000


def validate_target(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Only credential-free HTTP(S) targets are allowed")
    if parsed.port not in ALLOWED_PORTS:
        raise ValueError("Target port is not allowed")
    addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)}
    if not addresses:
        raise ValueError("Target did not resolve")
    for value in addresses:
        address = ipaddress.ip_address(value)
        if not address.is_global:
            raise ValueError("Private, loopback, link-local, reserved, and internal targets are blocked")
    return url


async def validate_request(route, counter: list[int]) -> None:
    counter[0] += 1
    if counter[0] > MAX_REQUESTS:
        await route.abort("blockedbyclient")
        return
    try:
        validate_target(route.request.url)
    except (ValueError, OSError):
        await route.abort("blockedbyclient")
        return
    if route.request.resource_type in {"media", "font"}:
        await route.abort("blockedbyclient")
        return
    await route.continue_()


async def capture(url: str, output_dir: Path) -> dict:
    from playwright.async_api import async_playwright

    validate_target(url)
    output_dir.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True, args=["--disable-dev-shm-usage", "--disable-extensions", "--disable-sync", "--no-first-run"])
        context = await browser.new_context(accept_downloads=False, ignore_https_errors=True, java_script_enabled=True, service_workers="block")
        counter = [0]
        await context.route("**/*", lambda route: validate_request(route, counter))
        page = await context.new_page()
        await page.goto(url, wait_until="domcontentloaded", timeout=20_000)
        await page.wait_for_timeout(1_500)
        final_url = page.url
        validate_target(final_url)
        title = (await page.title())[:500]
        visible_text = (await page.locator("body").inner_text(timeout=5_000))[:MAX_BODY_BYTES]
        forms = await page.locator("form").count()
        password_fields = await page.locator('input[type="password"]').count()
        payment_fields = await page.locator('input[autocomplete*="cc-"]').count()
        external_domains = sorted(set(await page.eval_on_selector_all("[src],[href]", "els => els.map(el => { try { return new URL(el.src || el.href, location.href).hostname } catch { return '' } }).filter(Boolean)")))
        screenshot = output_dir / "page.png"
        await page.screenshot(path=str(screenshot), full_page=False)
        await browser.close()
    text_hash = hashlib.sha256(visible_text.encode()).hexdigest()
    metadata = {
        "requested_url": url,
        "final_url": final_url,
        "title": title,
        "visible_text": visible_text,
        "forms": forms,
        "password_fields": password_fields,
        "payment_fields": payment_fields,
        "external_domains": external_domains[:200],
        "request_count": counter[0],
        "text_sha256": text_hash,
        "screenshot": "page.png",
    }
    (output_dir / "capture.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--output", default="/artifacts/capture")
    args = parser.parse_args()
    print(json.dumps(asyncio.run(capture(args.url, Path(args.output)))))


if __name__ == "__main__":
    main()
