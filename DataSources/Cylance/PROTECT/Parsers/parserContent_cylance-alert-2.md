#### Parser Content
```Java
{
Name = cylance-alert-2
  Vendor = Cylance
  Product = PROTECT
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|Skyformation|""", """destinationServiceName=CylanceProtect""", """externalID="""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\d+\s+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z)\s+""",
    """\WexternalID=({src_host}[\w.\-]+)""",
    """\Woutcome=({outcome}[^\s]+)""",
    """\Wcat=(|({alert_type}.+?))(\s+\w+=|\s*$)""",
    """\Wfname=(|({malware_url}.+?))(\s+\w+=|\s*$)""",
    """\Wproto=(|({file_name}.+?))(\s+\w+=|\s*$)""",
    """\Wmsg=(|({additional_info}.+?))(\s+\w+=|\s*$)""",
    """\Wsrc=({src_ip}[a-fA-F:\d.]+)""",
    """"cylance_score":({alert_severity}[^",]+)""",
    """\WdestinationServiceName=(|({device_name}.+?))(\s+\w+=|\s*$)""",
  ]
  DupFields = [ "alert_type->alert_name" ]
}
```