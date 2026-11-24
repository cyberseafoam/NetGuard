import csv
import io
import json


def json_report(report):
    return json.dumps(report, indent=2)


def csv_report(report):
    output = io.StringIO()
    fields = ['port', 'status', 'service', 'assessment', 'recommendation']
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows(report['results'])
    return output.getvalue()
