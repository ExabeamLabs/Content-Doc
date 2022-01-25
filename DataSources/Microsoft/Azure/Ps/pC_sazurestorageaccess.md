#### Parser Content
```Java
{
Name = s-azure-storage-access
  Vendor = Microsoft
  Product = Azure
  Lms = Splunk
  DataType = "cloud-storage-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""Skyformation""", """dproc=Blob Sync""" , """requestClientApplication=Azure"""]
  Fields = [
     """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
     """\d{1,100}\.\d{1,100};({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d).\d{1,100}Z;({activity}[^;]{1,2000});({outcome}[^;]{1,2000});({result_code}\d{1,100});\d{1,100};\d{1,100};(|[^;]{1,2000});(|({account}[^;]{1,2000}));(|[^;]{1,2000});(|[^;]{1,2000});(|[^;]{1,2000});"\/[^\/]{1,2000}\/({bucket}[^\/]{1,2000})\/.*\/({file_name}[^;"]{1,2000})";(|[^;]{1,2000});(|[^;]{1,2000});({src_ip}[^:]{1,2000}):({src_port}\d{1,100});(|[^;]{1,2000});(|[^;]{1,2000});({bytes_in}[^;]{1,2000});(|[^;]{1,2000});({bytes_out}[^;]{1,2000});(|[^;]{1,2000});(|[^;]{1,2000});(|[^;]{1,2000});"(|[^"]{1,2000})";(|[^;]{1,2000});(|[^;]{1,2000});"({user_agent}[^;"]{1,2000})"""
  ]
  DupFields = ["file_name->object"]


}
```