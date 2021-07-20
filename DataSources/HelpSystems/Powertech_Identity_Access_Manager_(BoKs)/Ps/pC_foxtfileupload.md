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
    """\d\dZ\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}(scp|sftp) - sshftl_upload_ok""",
    """user="{0,20}({user}[^"]{1,2000})"""",
    """Successful upload of file ({file_path}.+?) from """,
    """Successful upload of file (?:({src_file_dir}(\/[^\/]{1,2000})*\/))?({src_file_name}[^\/.]{1,2000}\.?({file_ext}[^\/]{0,2000})) from """,
    """fromhost="{0,20}({src_ip}[^"]{1,2000})"""",
    """({event_code}sshftl_upload_ok)"""
  ]
  DupFields = [ "host->dest_host", "src_file_name->file_name" ]
}
```