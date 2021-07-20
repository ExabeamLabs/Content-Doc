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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\Wapp=(|({app}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WdestinationServiceName=(|({event_subtype}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WdeviceNtDomain=(|({os}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdpriv=(|({category}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdproc=(|({process}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wproto=(|({alert_type}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d\.:]{1,2000})""",
    """"cves":\["({cve}[^"]{1,2000})"""",
    """"vulnerabilityId":"({resource_type}[^"]{1,2000})"""",
    """"severity":({alert_severity}\d{1,100})""",
    """"title":"({alert_name}[^"]{1,2000}?)\ ?"""",
    """"lastScanDateTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z)""",
    """"assetData":\{[^\{\}]{0,2000}?"hostName":"({src_host}[^"]{1,2000})"""",
    """"assetData":\{[^\{\}]{0,2000}?"type":"({asset_data_type}[^"]{1,2000})"""",
    """"assetData":\{[^\{\}]{0,2000}?"os":"({os}[^"]{1,2000})"""",
    """"assetData":\{[^\{\}]{0,2000}?"mac":"({src_mac_address}[^"]{1,2000})"""",
    """"osFingerprint":\{[^\{\}]{0,2000}?"architecture":"({os_architecture}[^"]{1,2000})"""",
    """"osFingerprint":\{[^\{\}]{0,2000}?"version":"({os_version}[^"]{1,2000})"""",
    """"osFingerprint":\{[^\{\}]{0,2000}?"type":"({os_type}[^"]{1,2000})"""",
    """"site":\{[^\{\}]{0,2000}?"id":({site_id}\d{1,100})""",
    """"site":\{[^\{\}]{0,2000}?"name":"({site_name}[^"]{1,2000})"""",
    """\Wmsg=(|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)"""
  ]
}
```