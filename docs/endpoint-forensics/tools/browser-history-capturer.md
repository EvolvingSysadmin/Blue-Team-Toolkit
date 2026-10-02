# Browser History Capturer

Foxton Forensics tool that collects browser history and related artifacts from a system for analysis in [Browser History Viewer](browser-history-viewer.md).

## When I Use It

* Collecting browser artifacts from a live Windows system without imaging the whole disk
* Cases where the question is "what sites did this user visit" and a full triage collection is more than needed

## Installation

* Download from <https://www.foxtonforensics.com/browser-history-capturer/>
* Runs from a USB drive without installation

## Common Tasks

| Task | Steps |
| :--- | :--- |
| Capture | Select user profiles -> select browsers -> select data (history, cache, cookies) -> select output directory -> Capture |
| Analyze | Open the output directory in [Browser History Viewer](browser-history-viewer.md) |

## Reading the Output

The capture is a copy of the browsers' own database files. Analysis happens in Browser History Viewer.

## Related

* [Browser History Viewer](browser-history-viewer.md)
* [KAPE](kape.md), which collects browser artifacts as part of a broader triage collection
* [Windows Artifacts](../windows-artifacts.md)

## Resources

* [Foxton Forensics](https://www.foxtonforensics.com/)
