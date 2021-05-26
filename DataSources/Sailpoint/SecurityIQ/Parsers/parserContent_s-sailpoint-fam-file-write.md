#### Parser Content
```Java
{
Name = s-sailpoint-fam-file-write
  DataType = "file-write"
  Conditions = ["""CEF:""", """|Sailpoint|FAM|""", """|Write File|""", """sproc=Netapp - CIFS"""]
  Fields = ${SailPointSIQNetAppCIFSTemplates.sailpoint-file-operation.Fields} [   
    """({accesses}Write)"""
  ]
}
sailpoint-file-operation = {
  Vendor = Sailpoint
  Product = FAM
  Lms = Splunk
  TimeFormat = "epoch_sec"
  Fields = [
    """\srt=({time}\d{1,20})""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """shost=({host}[\w\-.]{1,2000})""",
    """CEF:([^|]{0,2000}\|){4}({event_name}[^|]{1,2000})\|""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """sntdom=({domain}[^=]{1,2000})\s{1,1000}\w{1,2000}=""",
    """suser=({user}[^=]{1,2000})\s{1,1000}\w{1,2000}=""",
    """sproc=({app}[^=]{1,2000})\s{1,1000}\w{1,2000}=""",
    """fname=({file_name}[^=]{1,2000})\s{1,1000}\w{1,2000}=""",
    """filePath=({file_path}({file_parent}[^=]{1,2000})\\\\[^=]{1,2000})\s{1,1000}\w{1,2000}=""",
    """cs3=({file_ext}[^=]{1,2000})\s{1,1000}\w{1,2000}=""",
    """fileType=({file_type}[^=]{1,2000})\s{1,1000}\w{1,1000}="""
  ]

```