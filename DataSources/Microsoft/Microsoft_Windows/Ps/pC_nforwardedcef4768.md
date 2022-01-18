#### Parser Content
```Java
{
Name = n-forwarded-cef-4768
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = NitroCefSyslog
    DataType = "windows-4768"
    TimeFormat = "epoch"
    Conditions = ["|McAfee|ESM", "43-26304768"]
    Fields = ["""\|McAfee\|[^|]{1,2000}?\|[^|]{1,2000}?\|43-2630({event_code}\d{1,100})(0|1)\|""",
      """({event_name}A Kerberos authentication ticket \(TGT\) was requested)""",
      """\srt=({time}\d{1,100})""",
      """shost=({host}[^\s]{1,2000})""",
      """nitroCommandID=({result_code}.+?)\s{1,100}\w+=""",
      """src=({dest_ip}[a-fA-F:\d.]{1,2000})""",
      """sntdom=({domain}[^\s]{1,2000})""",
      """suser=({user}.+?)\s{1,100}\w+="""
      """nitroService_Name =({service_name}\S+)"""
    ]
  

}
```