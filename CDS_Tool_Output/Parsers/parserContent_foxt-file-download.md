#### Parser Content
```Java
{
Name = foxt-file-download
  Vendor = Fox BoKS ServerControl
  Product = Fox BoKS ServerControl
  Lms = Exabeam
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "sshftl_download_ok", "Successful download of file" ]
  Fields = [
    """clientTime="*({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z"*""",
    """\d\dZ\s+({host}[\w\-.]+)\s+(scp|sftp) - sshftl_download_ok""",
    """user="*({user}[^"]+)"""",
    """Successful download of file ({file_path}.+?) to """,
    """Successful download of file (?:({file_parent}(\/[^\/]+)*\/))?({file_name}[^\/.]+\.?({file_ext}[^\/]*)) to """,
    """fromhost="*({src_ip}[^"]+)"""",
    """({event_code}sshftl_download_ok)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```