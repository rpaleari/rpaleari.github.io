import os
import json
import sys
from bibparse import parse_bib

BIBTEX_SKIPPED_FIELDS = ["filepaper", "fileslides", "filename"]

class PubInfo:
    def __init__(self, key):
        self.key = key
        self.title = None
        self.authors = None
        self.conf = None
        self.address = None
        self.bib  = "Not available"
        self.file_paper = None
        self.file_slides = None

    def to_dict(self):
        data = {}
        for field in ("key", "title", "authors", "conf",
                      "address", "bib", "file_paper", "file_slides"):
            data[field] = getattr(self, field)
        return data


def bibtex_normalize(s):
    s = s.replace("$^{st}$", "<sup>st</sup>")
    s = s.replace("$^{nd}$", "<sup>nd</sup>")
    s = s.replace("$^{rd}$", "<sup>rd</sup>")
    s = s.replace("$^{th}$", "<sup>th</sup>")
    s = s.replace("\\", "")
    s = s.replace("{", "")
    s = s.replace("}", "")
    return s


def bibtex_tostring(p):
    s = ""
    for l in str(p).replace("\t", "  ").split("\n"):
        tmp = l.strip().lower()

        if len(tmp) == 0:
            continue

        skip = False
        for f in BIBTEX_SKIPPED_FIELDS:
             if tmp.startswith(f):
                 skip = True
                 break
        if skip: continue

        s += l + "\n"

    return s


def read_pubs(filename):
    pubs = []
    for pub in parse_bib(filename):
        p = PubInfo(pub.key)
        p.title = bibtex_normalize(pub.data.get("title", ""))
        p.authors = bibtex_normalize(pub.data.get("author", ""))
        p.conf = bibtex_normalize(pub.data.get("booktitle", ""))
        p.address = bibtex_normalize(pub.data.get("address", ""))
        p.bib = bibtex_tostring(pub)

        p.file_paper = bibtex_normalize(pub.data.get("filepaper", ""))
        if len(p.file_paper) and not p.file_paper.startswith("/"):
            p.file_paper = "/" + p.file_paper

        p.file_slides = bibtex_normalize(pub.data.get("fileslides", ""))
        if len(p.file_slides) and not p.file_slides.startswith("/"):
            p.file_slides = "/" + p.file_slides

        pubs.append(p)

    return pubs


def main():
    filename = sys.argv[1]
    assert os.path.isfile(filename)

    pubs = read_pubs(filename)
    data = []
    for pub in pubs:
        data.append(pub.to_dict())
    print json.dumps(data)


if __name__ == "__main__":
    main()
