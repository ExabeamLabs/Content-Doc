#### Parser Content
```Java
{
Name = rs2-badge-failed-physical-access-1
  DataType = "failed-physical-access"
  Conditions = ["""<DESCNAME><![CDATA[Access denied]]></DESCNAME>""", """<RDRNAME><"""]
  Fields = ${BadgePhysicalAccessTemplates.badge-physical-access.Fields} [
    """<DESCNAME><!\[CDATA\[({outcome}[^>]+?)\]+><\/DESCNAME>"""
  ]
}
```