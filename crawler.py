import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl(target, max_pages=5):
    visited = set()
    to_visit = [target]
    pages = []

    while to_visit and len(pages) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            r = requests.get(url, timeout=5)
            soup = BeautifulSoup(r.text, "html.parser")
            links = [urljoin(url, a.get("href")) for a in soup.find_all("a", href=True)]
            to_visit.extend([l for l in links if urlparse(l).netloc == urlparse(target).netloc])

            pages.append({"url": url, "response": r.text})
        except Exception as e:
            print("Error crawling", url, e)
            continue

    return pages
