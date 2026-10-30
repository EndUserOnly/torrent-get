import runpy,tempfile,json,unittest
from pathlib import Path
from unittest.mock import patch
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'payload/user/lib/torrent-get/security'))
m=runpy.run_path(str(ROOT/'payload/user/bin/torrent-mgmnt'))
g=m['remove_many'].__globals__
class Recovery(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
  for name,value in {'STATE_DIR':self.root,'STATE_FILE':self.root/'jobs.json','LOCK_FILE':self.root/'jobs.lock','LOG_DIR':self.root/'logs','RESUME_DIR':self.root/'resume','METADATA_APPROVAL_ROOT':self.root/'approvals','NETWORK_PAUSE_STATE':self.root/'network.json'}.items():g[name]=value
  g['RESUME_DIR'].mkdir(); g['METADATA_APPROVAL_ROOT'].mkdir()
  self.payload=self.root/'payload'; self.payload.write_text('keep downloaded bytes')
  self.jobs=[{'id':i,'state':st,'expected_payload':str(self.payload),'save_path':str(self.root),'pid':None,'infohash':'','log_path':str(self.root/'log')} for i,st in [(1,'ORPHANED'),(2,'PAUSED')]]
  self.save(); self.retire=patch.dict(g,{'retire_metadata_approval':lambda j:None}); self.retire.start(); self.controls=patch('subprocess.run'); self.controls.start()
 def tearDown(self):self.controls.stop(); self.retire.stop(); self.tmp.cleanup()
 def save(self):g['STATE_FILE'].write_text(json.dumps({'next_id':3,'jobs':self.jobs}))
 def state(self):return json.loads(g['STATE_FILE'].read_text())['jobs']
 def test_remove_archives_and_keeps_payload(self):
  (g['RESUME_DIR']/'job-1.fastresume').write_bytes(b'recovery')
  m['remove_many']([1]); self.assertEqual([j['id'] for j in self.state()],[2]); self.assertEqual(self.payload.read_text(),'keep downloaded bytes')
  self.assertEqual(next((self.root/'removed').glob('*/job-1.fastresume')).read_bytes(),b'recovery')
 def test_failed_shutdown_keeps_identity(self):
  with patch.dict(g,{'alive':lambda j:True}),patch('subprocess.run'):
   m['remove_many']([1])
  self.assertEqual(len(self.state()),2); self.assertFalse((self.root/'removed').exists())
 def test_prune_preview_and_paused_exclusion(self):
  m['prune'](dry_run=True); self.assertEqual(len(self.state()),2)
  m['prune'](); self.assertEqual([j['id'] for j in self.state()],[2])
 def test_pause_dead_orphan_preserves_source_and_data(self):
  m['pause_many']([1]); self.assertEqual(self.state()[0]['state'],'PAUSED'); self.assertTrue(self.payload.exists())
 def test_bad_metadata_path_does_not_block_reconciliation(self):
  self.jobs[0]['expected_payload']=str(self.root/('x'*300)); m['refresh'](self.jobs[0]); self.assertIn('payload_path_error',self.jobs[0])
 def test_unknown_id_leaves_queue_intact(self):
  with self.assertRaises(SystemExit):m['remove_many']([999])
  self.assertEqual(len(self.state()),2)
 def test_archive_failure_preserves_identity_and_resume(self):
  (g['RESUME_DIR']/'job-1.fastresume').write_bytes(b'recovery')
  with patch('shutil.copy2',side_effect=OSError('archive unavailable')):
   m['remove_many']([1])
  self.assertEqual(len(self.state()),2)
  self.assertEqual((g['RESUME_DIR']/'job-1.fastresume').read_bytes(),b'recovery')
 def test_pause_reconciliation_preserves_breaker_and_owned_ids(self):
  m['network_pause_write'](True,[1,999,2,1])
  with m['locked_state']():pass
  self.assertEqual(m['network_pause_read'](),{'paused':True,'jobs':[1,2]})
 def test_remove_reconciles_global_pause(self):
  m['network_pause_write'](True,[1,2])
  m['remove_many']([1])
  self.assertEqual(m['network_pause_read'](),{'paused':True,'jobs':[2]})
if __name__=='__main__':unittest.main()
