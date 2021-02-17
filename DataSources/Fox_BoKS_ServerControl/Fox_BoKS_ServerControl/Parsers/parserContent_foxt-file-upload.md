#### Parser Content
```Java
{
Name = foxt-file-upload
  Vendor = Fox BoKS ServerControl
  Product = Fox BoKS ServerControl
  Lms = Exabeam
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "sshftl_upload_ok", "Successful upload of file" ]
  Fields = [
    """clientTime="*({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z"*""",
    """\d\dZ\s+({host}[\w\-.]+)\s+(scp|sftp) - sshftl_upload_ok""",
    """user="*({user}[^"]+)"""",
    """Successful upload of file ({file_path}.+?) from """,
    """Successful upload of file (?:({src_file_dir}(\/[^\/]+)*\/))?({src_file_name}[^\/.]+\.?({file_ext}[^\/]*)) from """,
    """fromhost="*({src_ip}[^"]+)"""",
    """({event_code}sshftl_upload_ok)"""
  ]
  DupFields = [ "host->dest_host", "src_file_name->file_name" ]
}
```