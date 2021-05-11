#### Parser Content
```Java
{
Name = foxt-file-upload
  Vendor = HelpSystems
  Product = Powertech Identity Access Manager (BoKs)
  Lms = Exabeam
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "sshftl_upload_ok", "Successful upload of file" ]
  Fields = [
    """clientTime="{0,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z"{0,20}""",
    """\d\dZ\s{1,100}({host}[\w\-.]+)\s{1,100}(scp|sftp) - sshftl_upload_ok""",
    """user="{0,20}({user}[^"]+)"""",
    """Successful upload of file ({file_path}.+?) from """,
    """Successful upload of file (?:({src_file_dir}(\/[^\/]+)*\/))?({src_file_name}[^\/.]+\.?({file_ext}[^\/]*)) from """,
    """fromhost="{0,20}({src_ip}[^"]+)"""",
    """({event_code}sshftl_upload_ok)"""
  ]
  DupFields = [ "host->dest_host", "src_file_name->file_name" ]
}
```