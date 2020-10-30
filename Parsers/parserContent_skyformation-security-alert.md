#### Parser Content
```Java
{
Name = skyformation-security-alert
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct
  DataType = "security-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|Skyformation|SkyFormation Cloud Apps Security|""", """cat=security-alert""", """|general-alert|""", """destinationServiceName=Azure""", """requestClientApplication=Azure"""]
  Fields = [
    """({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)\s+[^\s]+\s+Skyformation""",   
    """msg=({additional_info}.+?)\s+(\w+=|$)""",
    """flexString1=({activity}.+?)\s*\w+=""",
    """request=({outcome}.+?)\s*\w+=""",
    """"severity":"({alert_severity}[^"]+)""",
    """cs1=({alert_name}.+?)\s+\w+=""",
    """sourceServiceName=\s*({service}.+?)\s+\w+""",
    """suser=(Azure Security Center|({user}.+?))\s+\w+=""",
    """intent":"\[\\"({alert_type}[^\\"]+)""",
 ]
}
```