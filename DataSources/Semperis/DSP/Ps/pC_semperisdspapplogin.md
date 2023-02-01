#### Parser Content
```Java
{
Name = semperis-dsp-app-login
  Vendor = Semperis
  Product = DSP
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "dd/MMM/yyyy HH:mm:ss.SSSS"
  Conditions = [  """Login to DSP""","""Access Granted:""","""Trustee Name:""" ]
  Fields = [
    """Occured at \([^:]{1,2000}: ({time}\d{2}\/\d{1,2}\/\d{4}\s\d{2}:\d{2}:\d{2}\.\d{4})""",
    """Operation:\s{0,100}({event_name}Login to DSP)""",
    """Result:\s{0,100}({outcome}[\S]{1,2000})""",
    """Trustee Name:\s{0,100}(((NT AUTHORITY)|({domain}[^\\:]{1,2000}?))\\+)?((SYSTEM)|({user}[^:\s]{1,2000}))""",
    """Product:\s{0,100}({app}DSP)""",
    """Source:\s{0,100}({src_ip}[A-Fa-f\d\.:]{1,2000}?):"""
  ]


}
```