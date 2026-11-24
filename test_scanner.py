import socket
import pytest
from scanner import validate_target, scan_port, scan_ports
from service_checker import identify_service
from risk_analyzer import assess_port
from report_generator import csv_report, json_report

@pytest.mark.parametrize('target', ['127.0.0.1', '::1'])
def test_loopback(target):
    assert validate_target(target) == target

@pytest.mark.parametrize('target', ['example.com', '192.0.2.1', '192.168.1.1', 'bad', '127.0.0.2'])
def test_reject_other_targets(target):
    with pytest.raises(ValueError):
        validate_target(target)

def test_open_port():
    with socket.socket() as server:
        server.bind(('127.0.0.1', 0))
        server.listen()
        port = server.getsockname()[1]
        assert scan_port('127.0.0.1', port)['status'] == 'Open'
        rows, duration = scan_ports('127.0.0.1', [port, port])
        assert len(rows) == 1 and duration >= 0

def test_invalid_ports():
    for ports in ([], [0], [65536], range(1, 258)):
        with pytest.raises(ValueError):
            scan_ports('127.0.0.1', ports)

def test_services():
    assert identify_service(443) == 'HTTPS'
    assert identify_service(65000) == 'Unknown'

def test_assessment():
    assert assess_port(23, 'Open')[0] == 'Review'
    assert assess_port(23, 'Closed')[0] == 'Not assessed'

def test_reports():
    report = {'results':[{'port':80,'status':'Open','service':'HTTP','assessment':'Review','recommendation':'Check'}]}
    assert '80,Open,HTTP,Review,Check' in csv_report(report)
    assert '"port": 80' in json_report(report)
