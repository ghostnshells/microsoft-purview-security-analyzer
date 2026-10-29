import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd
import pyarrow as pa
from streamlit.testing.v1 import AppTest

from dashboard_views import event_table, group_locations, create_activity_map
from security_analyzer import parse_audit_logs, apply_filters

ROOT = Path(__file__).resolve().parents[1]

class DashboardTests(unittest.TestCase):
    def test_tables_handle_mixed_dates_and_values(self):
        frame = event_table([{'Timestamp':'bad', 'AnomalyTypes':['A','B'], 'UserId':1},
                             {'Timestamp':'2026-01-01T12:00:00+02:00', 'UserId':'alice'}])
        self.assertEqual(frame.Timestamp.tolist(), ['Unknown','2026-01-01 10:00:00 UTC'])
        self.assertEqual(frame.AnomalyTypes.iloc[0], 'A, B')
        pa.Table.from_pandas(frame)

    def test_map_is_bounded_and_escapes_input(self):
        event = {'Latitude':40, 'Longitude':-70, 'Country':'US', 'City':'<script>x</script>',
                 'Operation':'<b>delete</b>', 'Timestamp':'2026-01-01'}
        groups = group_locations([event]*1000 + [dict(event,Latitude=float('nan')), dict(event,Longitude=181)])
        self.assertEqual(len(groups),1)
        html = create_activity_map(groups).get_root().render()
        self.assertLess(len(html),12000)
        self.assertNotIn('<script>x</script>',html)
        self.assertIn('1,000 events',html)
        unknown = dict(event, Timestamp='bad')
        self.assertIn('Unknown time', create_activity_map(group_locations([unknown])).get_root().render())

    def test_csv_excel_and_full_dashboard(self):
        rows = [{'CreationDate':'2026-01-01T01:00:00', 'Operation':op, 'UserId':'test@example.test',
                 'AuditData':json.dumps({'ClientIP':ip,'SourceFileName':'demo.txt'})}
                for op,ip in [('FileAccessed','192.168.1.160'),('SoftDelete','8.8.8.8')]]
        df = pd.DataFrame(rows)
        with tempfile.TemporaryDirectory() as d:
            for ext in ['csv','xlsx']:
                path = Path(d)/('audit.'+ext)
                df.to_csv(path,index=False) if ext=='csv' else df.to_excel(path,index=False)
                events=parse_audit_logs(str(path))
                self.assertEqual(len(events),2)
                self.assertIn('RiskLevel',apply_filters(events,{})[0])
        upload = io.BytesIO(df.to_csv(index=False).encode()); upload.name='audit.csv'
        with patch('streamlit.file_uploader',return_value=upload):
            app=AppTest.from_file(str(ROOT/'app_new.py')).run(timeout=30)
            self.assertFalse(list(app.exception))
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertGreaterEqual(len(app.dataframe),4)
            self.assertEqual(app.metric[0].value,'2')
            app.run(timeout=30)
            self.assertFalse(list(app.error))
            # Replacing an upload with the same filename must invalidate results.
            upload.seek(0); upload.truncate()
            upload.write(df.iloc[:1].to_csv(index=False).encode()); upload.seek(0)
            app.run(timeout=30)
            self.assertFalse(list(app.error))
            self.assertEqual(app.metric[0].value,'1')

if __name__=='__main__':
    unittest.main()
