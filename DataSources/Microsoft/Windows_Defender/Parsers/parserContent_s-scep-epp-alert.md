#### Parser Content
```Java
{
Name = s-scep-epp-alert
  Vendor = Microsoft
  Product = Windows Defender
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """vendor_product=SystemCenterEndpointProtection""" ]
  Fields = [
    """dest_name=({src_host}[^\s]+)\s""",
    """DetectionTime=({time}\d{1,100})""",
    """user="{0,20}({domain}[^\\]+)?(\\)*({user}.+?)"{0,20}\starget""",
    """severity=({alert_severity}.+?)\s{1,100}category="{0,20}({alert_type}.+?)"{0,20}\saction""",
    """resourceid=({alert_id}[^\s]+)\s{1,100}""",
    """signature=({alert_name}[^\s]+)\s{1,100}""",
    """exabeam_host=({host}[\w\-.]+)"""
  ]
}
```