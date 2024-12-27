import nbformat
from nbconvert import PDFExporter
from nbconvert.preprocessors import ExecutePreprocessor
import os
import datetime


def run_notebook(notebook_path, output_path):
    """
    Executes a Jupyter notebook and converts it to a PDF.

    Parameters:
    notebook_path (str): The path to the notebook file to be executed.
    output_path (str): The path where the output PDF should be saved.
    """
    # Load the notebook
    with open(notebook_path) as f:
        nb = nbformat.read(f, as_version=4)

    # Execute the notebook
    ep = ExecutePreprocessor(timeout=600, kernel_name='python3')
    ep.preprocess(nb, {'metadata': {'path': './'}})

    # Save the executed notebook
    with open(notebook_path, 'w') as f:
        nbformat.write(nb, f)

    # Convert the notebook to PDF
    pdf_exporter = PDFExporter()
    pdf_data, resources = pdf_exporter.from_notebook_node(nb)

    # Write the PDF to a file
    with open(output_path, 'wb') as f:
        f.write(pdf_data)

# create a results directory if it does not exist
os.makedirs('../results', exist_ok=True)

# Run the function using the below arguments. (You can change the arguments as needed)
notebook_path = '../notebooks/analysis.ipynb'
output_path = '../results/analysis_results.pdf'

# Add mmddyyHHMM to the output path to avoid overwriting
output_path = output_path.replace('.pdf', f'_{datetime.datetime.now().strftime("%m%d%y%H%M")}.pdf')

# If the output path does not exist, create it
os.makedirs(os.path.dirname(output_path), exist_ok=True)

run_notebook(notebook_path, output_path)
print(f'The results have been saved to {output_path}')
