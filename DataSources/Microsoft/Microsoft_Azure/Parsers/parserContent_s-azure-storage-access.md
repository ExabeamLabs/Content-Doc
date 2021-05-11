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
     """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
     """\d{1,100}\.\d{1,100};({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d).\d{1,100}Z;({activity}[^;]+);({outcome}[^;]+);({result_code}\d{1,100});\d{1,100};\d{1,100};(|[^;]+);(|({account}[^;]+));(|[^;]+);(|[^;]+);(|[^;]+);"\/[^\/]+\/({bucket}[^\/]+)\/.*\/({file_name}[^;"]+)";(|[^;]+);(|[^;]+);({src_ip}[^:]+):({src_port}\d{1,100});(|[^;]+);(|[^;]+);({bytes_in}[^;]+);(|[^;]+);({bytes_out}[^;]+);(|[^;]+);(|[^;]+);(|[^;]+);"(|[^"]+)";(|[^;]+);(|[^;]+);"({user_agent}[^;"]+)"""
  ]
  DupFields = ["file_name->object"]
}
```