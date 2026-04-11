import argparse
import asyncio
import logging
import sys
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from agent.report import PenTestReport
from agent.workflow import run_workflow

logger = logging.getLogger("main")


def setup_logging() -> None:
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    session_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"session_{session_ts}.log"

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(fmt)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(file_handler)
    root.addHandler(console_handler)

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    logging.getLogger("agent").info("Logging initialised — writing to %s", log_file)


def render_report(report: PenTestReport) -> Path:
    env = Environment(loader=FileSystemLoader("template"), autoescape=True)
    template = env.get_template("report.html")
    html = template.render(report=report)

    report_dir = Path("reports")
    report_dir.mkdir(exist_ok=True)
    safe_target = report.target.replace(".", "_")
    output_path = report_dir / f"{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    output_path.write_text(html, encoding="utf-8")
    return output_path


async def run_target(target: str, semaphore: asyncio.Semaphore) -> tuple[str, Path | None, Exception | None]:
    """Run a single target's workflow behind a concurrency semaphore."""
    async with semaphore:
        logger.info("Starting engagement: %s", target)
        try:
            report = await run_workflow(target)
            path = render_report(report)
            logger.info("Engagement complete: %s → %s", target, path)
            return (target, path, None)
        except Exception as e:
            logger.error("Engagement failed: %s — %s: %s", target, type(e).__name__, e)
            return (target, None, e)


async def main():
    parser = argparse.ArgumentParser(description="Red Team Agent — multi-target engagement")
    parser.add_argument(
        "targets",
        nargs="+",
        help="One or more target IPs or hostnames",
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=2,
        help="Max concurrent engagements (default: 2)",
    )
    args = parser.parse_args()

    setup_logging()

    targets = args.targets
    semaphore = asyncio.Semaphore(args.concurrency)

    logger.info(
        "Launching %d engagement(s) with concurrency=%d: %s",
        len(targets), args.concurrency, ", ".join(targets),
    )

    results = await asyncio.gather(
        *[run_target(t, semaphore) for t in targets]
    )

    print(f"\n{'=' * 60}")
    print("ENGAGEMENT SUMMARY")
    print(f"{'=' * 60}")
    for target, path, error in results:
        if error:
            print(f"  FAIL  {target} — {type(error).__name__}: {error}")
        else:
            print(f"  OK    {target} → {path}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    asyncio.run(main())