#### Parser Content
```Java
{
Name = cylance-alert-2
  Vendor = BlackBerry
  Product = BlackBerry Protect
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|Skyformation|""", """destinationServiceName=CylanceProtect""", """externalID="""]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\d{1,100}\s{1,100}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z)\s{1,100}""",
    """\WexternalID=({src_host}[\w.\-]+)""",
    """\Woutcome=({outcome}[^\s]+)""",
    """\Wcat=(|({alert_type}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """Security Alert Detected by.*?Category \[({alert_type}[^\]\[,]+?)\]"""
    """Security Alert Detected by.*?SubCategory \[({category}[^\]\[,]+?)\]"""
    """\Wfname=(|({malware_url}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wfname=(|({process}({process_directory}(?:(\w+:)*([\\\/]+[^\\\/"]+?)+?)?[\\\/]+)({process_name}[^"\\\/]+?)))\s{1,100}(\w+=|$)""",
    """\Wproto=(|({file_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wmsg=(|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F:\d.]+)""",
    """"cylance_score":({alert_severity}[^",]+)""",
    """\WdestinationServiceName=(|({device_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"md5":"({md5}[^"]+)""",
    """"name":"({file_name}[^"]+)"""",
    """"sha256":"({file_hash}[^"]+)""""
  ]
  DupFields = [ "alert_type->alert_name", "file_name->name_at", "file_hash->sha256_at" ]
}
```