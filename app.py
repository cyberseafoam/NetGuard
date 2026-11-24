import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timezone
from scanner import scan_ports
from service_checker import SERVICES, identify_service
from risk_analyzer import assess_port
from report_generator import csv_report, json_report

st.set_page_config(page_title='NetGuard', page_icon='🛡️', layout='wide')
st.title('🛡️ NetGuard')
st.caption('Local TCP security assessment | v1.0')
st.info('Active scanning is restricted to your own loopback interface. Run locally; hosted apps scan the hosting server, not your computer.')
mode = st.sidebar.radio('Mode', ['Simulated demo', 'Local scan', 'How it works'])
if 'history' not in st.session_state:
    st.session_state.history = []
if mode == 'How it works':
    st.markdown('NetGuard attempts bounded TCP connections. A successful connection indicates an open TCP port. Common service names are inferred from port numbers, not verified. Review flags are configuration suggestions, not confirmed vulnerabilities. Closed means a connection was refused; unknown means another connection error or timeout. UDP is not tested.')
    st.stop()
if mode == 'Local scan':
    target = st.selectbox('Loopback target', ['127.0.0.1', '::1'])
    selection = st.radio('Port selection', ['Common ports', 'Custom range'])
    if selection == 'Common ports':
        ports = sorted(SERVICES)
    else:
        a = st.number_input('First port', 1, 65535, 8000)
        b = st.number_input('Last port', 1, 65535, 8010)
        ports = range(a, b + 1) if a <= b and b - a < 256 else []
    if st.button('Start local scan', type='primary'):
        try:
            with st.spinner('Checking local TCP ports...'):
                rows, duration = scan_ports(target, ports)
            st.session_state.local_result = (target, rows, duration)
        except ValueError as exc:
            st.session_state.pop('local_result', None)
            st.error(str(exc))
    result = st.session_state.get('local_result')
else:
    result = ('Simulated host', [{'port':p,'status': 'Open' if p in (22,80,443,3389) else 'Closed'} for p in sorted(SERVICES)], 0.0)
if result:
    target, rows, duration = result
    findings = []
    for row in rows:
        assessment, recommendation = assess_port(row['port'], row['status'])
        findings.append({**row, 'service':identify_service(row['port']), 'assessment':assessment, 'recommendation':recommendation})
    report = {'target':target, 'mode':mode, 'duration_seconds':duration, 'results':findings}
    st.subheader(f'Results: {target}')
    if mode == 'Simulated demo':
        st.warning('Illustrative data only. No network connections were made.')
    else:
        st.caption('Results reflect the last completed scan, not necessarily the current input selection.')
    df = pd.DataFrame(findings)
    cols = st.columns(4)
    cols[0].metric('Ports checked', len(df))
    cols[1].metric('Open ports', int((df.status == 'Open').sum()))
    cols[2].metric('Review flags', int((df.assessment == 'Review').sum()))
    cols[3].metric('Duration', f'{duration:.3f} s' if mode == 'Local scan' else 'Simulated')
    counts = df.status.value_counts().rename_axis('Status').reset_index(name='Count')
    st.plotly_chart(px.bar(counts, x='Status', y='Count', color='Status'), use_container_width=True)
    st.dataframe(df, hide_index=True, use_container_width=True)
    st.download_button('Download JSON', json_report(report), 'netguard_report.json', 'application/json')
    st.download_button('Download CSV', csv_report(report), 'netguard_report.csv', 'text/csv')
    if st.button('Save result to session history'):
        st.session_state.history.append({'saved_at':datetime.now(timezone.utc).isoformat(), **report})
        st.session_state.history = st.session_state.history[-20:]
if st.session_state.history:
    with st.expander('Session history'):
        st.dataframe([{k:v for k,v in item.items() if k != 'results'} for item in st.session_state.history], hide_index=True)
        st.download_button('Export history', json_report(st.session_state.history), 'netguard_history.json', 'application/json')
        if st.button('Clear history'):
            st.session_state.history = []
            st.rerun()
