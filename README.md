An example to demonstrate how to call Google StackDriver Trace API in PYTHON.

## Steps
1. Install pip

2. Install gcloud SDK and run ```gcloud init``` and ```gcloud beta auth application-default login```

3. Follow instructions on: https://pypi.python.org/pypi/gax-google-devtools-cloudtrace-v1
   to set up virtual environment and install gax-google-devtools-cloudtrace-v1 package.

4. Run sample code to list_traces, get_trace, patch_traces 
```
$ python trace_sample_gcloud.py <your GCP project id>
```

5. If it's successful, you will see trace printed and links to view trace patched at Google Cloud Console.
