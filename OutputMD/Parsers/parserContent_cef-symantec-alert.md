#### Parser Content
```Java
{
Name = cef-symantec-alert
  Vendor = Symantec
  Product = Symantec WSS
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation|""", """|security-threat-detected|""", """destinationServiceName=Symantec WSS""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\d+\s+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z)\s+({host}[\w\-.]+)\s+Skyformation""",
    """\WexternalID=({src_host}[\w\-.]+)""",
    """\Wdpriv=(|({alert_type}.+?))(\s+\w+=|\s*$)""",
    """\Wfname=(|({malware_url}.+?))(\s+\w+=|\s*$)""",
    """\Wproto=(|({alert_name}.+?))(\s+\w+=|\s*$)""",
    """\Wmsg=(|({additional_info}.+?))(\s+\w+=|\s*$)""",
    """\Wsrc=({src_ip}[a-fA-F:\d.]+)""",
    """\Wdst=({dest_ip}[a-fA-F:\d.]+)""",
    """\Wsuser=(({domain}[^\\\s]+)\\+)?(non-interactive-user|({user}[^\\\s]+))""",
    """\Woutcome=(|({outcome}.+?))(\s+\w+=|\s*$)""",
    """\Wdproc=(|({process_name}.+?))(\s+\w+=|\s*$)""",
  ]
  DupFields = ["host->dest_host"]
}
```