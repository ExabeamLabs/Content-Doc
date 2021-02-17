#### Parser Content
```Java
{
Name = s-azure-storage-access
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Splunk
  DataType = "cloud-storage-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""Skyformation""", """dproc=Blob Sync""" , """requestClientApplication=Azure"""]
  Fields = [
     """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
     """\d+\.\d+;({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d).\d+Z;({activity}[^;]+);({outcome}[^;]+);({result_code}\d+);\d+;\d+;(|[^;]+);(|({account}[^;]+));(|[^;]+);(|[^;]+);(|[^;]+);"\/[^\/]+\/({bucket}[^\/]+)\/.*\/({file_name}[^;"]+)";(|[^;]+);(|[^;]+);({src_ip}[^:]+):({src_port}\d+);(|[^;]+);(|[^;]+);({bytes_in}[^;]+);(|[^;]+);({bytes_out}[^;]+);(|[^;]+);(|[^;]+);(|[^;]+);"(|[^"]+)";(|[^;]+);(|[^;]+);"({user_agent}[^;"]+)"""
  ]
  DupFields = ["file_name->object"]
}
```