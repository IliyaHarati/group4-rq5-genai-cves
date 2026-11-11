from pathlib import Path
import nbformat
from nbclient import NotebookClient
from nbconvert import HTMLExporter
ROOT=Path(__file__).resolve().parents[1]
p=ROOT/'notebooks/RQ5_Analysis.ipynb'
nb=nbformat.read(p,as_version=4)
NotebookClient(nb,timeout=120,kernel_name='python3',resources={'metadata':{'path':str(ROOT)}}).execute()
assert all(c.execution_count is not None for c in nb.cells if c.cell_type=='code')
assert not any(o.output_type=='error' for c in nb.cells if c.cell_type=='code' for o in c.outputs)
nbformat.write(nb,p)
body,_=HTMLExporter(template_name='lab').from_notebook_node(nb)
(ROOT/'reports/RQ5_Notebook.html').write_text(body,encoding='utf-8')
print('All notebook cells executed successfully; HTML exported.')
