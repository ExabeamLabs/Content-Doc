#### Parser Content
```Java
{
Name = netwrix-ad-ds-access
  DataType = "ds-access"
  Conditions = [ """CEF:0|Netwrix|Active Directory|""" ]
  Fields = ${NetWrixParserTemplates.netwrix-app-activity-2.Fields}[
    """CEF:0\|Netwrix\|Active Directory\|[^\|]+\|[^\|]+\|({activity}[^\|]+)\|""",
    """cat=({object_class}[^\s]+).+?filePath=({object_dn}[^\s]+\\({object}[^\s]+?)) start=""",
    """cat=computer.+?filePath=[^\s]+\\({computer_name}[^\s]+?) start=""",
    """cat=user.+?filePath=[^\s]+\\({target_user}[^\s]+?) start=""",
    """cat=group.+?filePath=\\+?([^\\]+\\+)*?({target_group}[^\\]+) start=""",
    """msg=Object Path changed from "+({old_value}[^"]+)"+ to "+({new_value}[^"]+)"+""",
  ]
}
```