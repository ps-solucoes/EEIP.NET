namespace EEIP.NET.Tests.SuspectedBugs;

/// <summary>For tests that measure timing or allocations and must not share the CPU with other tests.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class NonParallelCollection
{
    public const string Name = "Suspected bugs (not parallelized)";
}
