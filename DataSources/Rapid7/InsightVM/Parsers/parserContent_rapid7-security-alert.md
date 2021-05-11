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
    """\Wapp=(|({app}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WdestinationServiceName=(|({event_subtype}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WdeviceNtDomain=(|({os}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdpriv=(|({category}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdproc=(|({process}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wproto=(|({alert_type}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d\.:]+)""",
    """"cves":\["({cve}[^"]+)"""",
    """"vulnerabilityId":"({resource_type}[^"]+)"""",
    """"severity":({alert_severity}\d{1,100})""",
    """"title":"({alert_name}[^"]+?)\ ?"""",
    """"lastScanDateTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z)""",
    """"assetData":\{[^\{\}]*?"hostName":"({src_host}[^"]+)"""",
    """"assetData":\{[^\{\}]*?"type":"({asset_data_type}[^"]+)"""",
    """"assetData":\{[^\{\}]*?"os":"({os}[^"]+)"""",
    """"assetData":\{[^\{\}]*?"mac":"({src_mac_address}[^"]+)"""",
    """"osFingerprint":\{[^\{\}]*?"architecture":"({os_architecture}[^"]+)"""",
    """"osFingerprint":\{[^\{\}]*?"version":"({os_version}[^"]+)"""",
    """"osFingerprint":\{[^\{\}]*?"type":"({os_type}[^"]+)"""",
    """"site":\{[^\{\}]*?"id":({site_id}\d{1,100})""",
    """"site":\{[^\{\}]*?"name":"({site_name}[^"]+)"""",
    """\Wmsg=(|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)"""
  ]
}
```