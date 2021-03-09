#### Parser Content
```Java
{
Name = rapid7-security-alert
  Vendor = Rapid7
  Product = InsightVM
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"vulnerabilityId":""", """"assetData":""", """"severity":""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """\Wapp=(|({app}.+?))(\s+\w+=|\s*$)""",
    """\WdestinationServiceName=(|({event_subtype}.+?))(\s+\w+=|\s*$)""",
    """\WdeviceNtDomain=(|({os}.+?))(\s+\w+=|\s*$)""",
    """\Wdpriv=(|({category}.+?))(\s+\w+=|\s*$)""",
    """\Wdproc=(|({process}.+?))(\s+\w+=|\s*$)""",
    """\Wproto=(|({alert_type}.+?))(\s+\w+=|\s*$)""",
    """\Wsrc=({src_ip}[a-fA-F\d\.:]+)""",
    """"cves":\["({cve}[^"]+)"""",
    """"vulnerabilityId":"({resource_type}[^"]+)"""",
    """"severity":({alert_severity}\d+)""",
    """"title":"({alert_name}[^"]+?)\ ?"""",
    """"lastScanDateTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z)""",
    """"assetData":\{[^\{\}]*?"hostName":"({src_host}[^"]+)"""",
    """"assetData":\{[^\{\}]*?"type":"({asset_data_type}[^"]+)"""",
    """"assetData":\{[^\{\}]*?"os":"({os}[^"]+)"""",
    """"assetData":\{[^\{\}]*?"mac":"({src_mac_address}[^"]+)"""",
    """"osFingerprint":\{[^\{\}]*?"architecture":"({os_architecture}[^"]+)"""",
    """"osFingerprint":\{[^\{\}]*?"version":"({os_version}[^"]+)"""",
    """"osFingerprint":\{[^\{\}]*?"type":"({os_type}[^"]+)"""",
    """"site":\{[^\{\}]*?"id":({site_id}\d+)""",
    """"site":\{[^\{\}]*?"name":"({site_name}[^"]+)"""",
    """\Wmsg=(|({additional_info}.+?))(\s+\w+=|\s*$)"""
  ]
}
```