#### Parser Content
```Java
{
Name = semperis-dsp-app-login-1
  Vendor = Semperis
  Product = DSP
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Semperis.DSP""", """[OperationType] LoginDSP""", """[OperationResult] Granted""" ]
  Fields = [
  """OperationTime\]\s({time}\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}\.\d{1,3}Z)"""
  """\w{3,4}\s\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}\s({host}[\w\-.]{1,2000})"""
  """OperationSource\]\s({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9]{1,2000}:[A-Fa-f0-9:]{1,2000}))"""
  """({event_name}DSP Login)"""
  """OperationResult\]\s({action}[^\s]{1,2000})"""
  """TrusteeName\]\s(NT AUTHORITY|({domain}[^\\\s]{1,2000}))[\\]{1,100}(SYSTEM|({user}[^\s]{1,2000}))"""
  """({app}Semperis.DSP)"""
  """({outcome}Success)"""
  ]


}
```