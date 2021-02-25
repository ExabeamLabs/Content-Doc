#### Parser Content
```Java
{
Name = rs2-badge-failed-physical-access-2
  DataType = "failed-physical-access"
  Conditions = ["""<DESCNAME><![CDATA[Elevator access denied]]></DESCNAME>""", """<RDRNAME><"""]
  Fields = ${BadgePhysicalAccessTemplates.badge-physical-access.Fields} [
    """<DESCNAME><!\[CDATA\[Elevator ({outcome}[^>]+?)\]+><\/DESCNAME>"""
  ]
}
```