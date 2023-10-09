namespace Args;

[AttributeUsage(AttributeTargets.Class)]
public class ModuleAttribute : Attribute
{
    public string ModuleName { get; }
    public string Description { get; set; } = null;

    public ModuleAttribute(string moduleName)
    {
        ModuleName = moduleName;
    }

}