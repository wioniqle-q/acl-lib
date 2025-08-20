using Acl.Fs.Cli.Models;

namespace Acl.Fs.Cli.Abstractions.Services;

internal interface IOperationResultHandler
{
    Task<OperationResult> HandleOperationAsync(OperationRequest request);
}