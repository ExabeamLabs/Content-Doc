#### Parser Content
```Java
{
Name = semperis-dsp-ds-access-2
  Vendor = Semperis
  Product = DSP
  Lms = Splunk
  DataType = "ds-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """ModifyObject""", """Semperis.DSP""", """[ChangeId]""" ]
  Fields = [
  """OriginatingTime\]\s({time}\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}\.\d{1,3}Z)"""
  """OriginatingServer\]\s({host}[\w\-.]{1,2000})"""
  """ObjectModificationType\]\s({event_name}[^\[]{1,2000}?)\s{1,20}\["""
  """AttributeModificationType\]\s({activity_type}[^\[]{1,2000}?)\s{1,20}\["""
  """OriginatingUsers\]\s({domain}[^\\;\s]{1,2000})[\\]{1,100}({user}[^;\s]{1,2000})"""
  """OriginatingUserWorkstations\]\s{1,100}({src_host}[\w\-.]{1,2000})"""
  """ClassName\]\s({object_class}[^\s]{1,2000})"""
  """DistinguishedName\]\s({object_dn}[^\[]{1,2000}?)\s{1,20}\["""
  """AttributeName\]\s({attribute}[^\s]{1,2000})"""
  """StringValueFrom\]\s[\{|"]{0,100}({old_attribute}[^\s]{1,2000})"""
  """StringValueTo\]\s(\s{0,100}|\{|({new_attribute}[^"]{1,2000}?))\s{0,100}("|$)"""
  """({app}Semperis.DSP)"""
  ]


}
```