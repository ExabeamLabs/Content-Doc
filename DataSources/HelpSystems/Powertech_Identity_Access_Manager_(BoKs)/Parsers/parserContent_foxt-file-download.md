#### Parser Content
```Java
{
Name = foxt-file-download
  Vendor = HelpSystems
  Product = Powertech Identity Access Manager (BoKs)
  Lms = Exabeam
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ "sshftl_download_ok", "Successful download of file" ]
  Fields = [
    """clientTime="{0,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z"{0,20}""",
    """\d\dZ\s{1,100}({host}[\w\-.]+)\s{1,100}(scp|sftp) - sshftl_download_ok""",
    """user="{0,20}({user}[^"]+)"""",
    """Successful download of file ({file_path}.+?) to """,
    """Successful download of file (?:({file_parent}(\/[^\/]+)*\/))?({file_name}[^\/.]+\.?({file_ext}[^\/]*)) to """,
    """fromhost="{0,20}({src_ip}[^"]+)"""",
    """({event_code}sshftl_download_ok)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```