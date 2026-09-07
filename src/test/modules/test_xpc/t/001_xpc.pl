use strict;
use warnings FATAL => 'all';
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

if ($^O ne 'darwin')
{
	plan skip_all => 'XPC tests only run on macOS';
}

my $node = PostgreSQL::Test::Cluster->new('xpc_node');
$node->init;

my $svc_name = "org.postgresql.test.xpc." . $$;

# Configure node with XPC enabled and NO TCP or unix socket
$node->append_conf('postgresql.conf', qq{
xpc = on
xpc_service_name = '$svc_name'
listen_addresses = ''
unix_socket_directories = ''
});

$node->start;

# 1. Test XPC ping action
my ($stdout, $stderr) = run_command(['test_xpc', 'ping', $svc_name]);
diag("ping stdout: $stdout");
diag("ping stderr: $stderr");
like($stdout, qr/STATUS: OK/, 'XPC ping returns OK status');
like($stdout, qr/POSTMASTER_PID: \d+/, 'XPC ping returns valid postmaster PID');

# 2. Test XPC query action
($stdout, $stderr) = run_command(['test_xpc', 'query', $svc_name, "SELECT 42 AS num, 'hello_xpc' AS greeting;"]);
like($stdout, qr/STATUS: OK/, 'XPC query returns OK status');
like($stdout, qr/COMMAND_TAG: SELECT 1/, 'XPC query returns SELECT 1');
like($stdout, qr/COLUMNS: num greeting/, 'XPC query returns expected columns');
like($stdout, qr/ROW: 42 hello_xpc/, 'XPC query returns expected row data');

# 3. Test table creation, insert, and select over XPC query
($stdout, $stderr) = run_command(['test_xpc', 'query', $svc_name, "CREATE TABLE test_xpc_items (id int, val text);"]);
like($stdout, qr/STATUS: OK/, 'XPC CREATE TABLE succeeds');

($stdout, $stderr) = run_command(['test_xpc', 'query', $svc_name, "INSERT INTO test_xpc_items VALUES (1, 'foo'), (2, 'bar');"]);
like($stdout, qr/STATUS: OK/, 'XPC INSERT succeeds');

($stdout, $stderr) = run_command(['test_xpc', 'query', $svc_name, "SELECT id, val FROM test_xpc_items ORDER BY id;"]);
like($stdout, qr/STATUS: OK/, 'XPC SELECT succeeds');
like($stdout, qr/ROW: 1 foo/, 'XPC SELECT row 1 match');
like($stdout, qr/ROW: 2 bar/, 'XPC SELECT row 2 match');

# 4. Test libpq connection via xpc_service
my ($lpq_stdout, $lpq_stderr) = run_command(['test_xpc', 'libpq', $svc_name, "SELECT id, val FROM test_xpc_items WHERE id = 2;"]);
diag("libpq stdout: $lpq_stdout");
diag("libpq stderr: $lpq_stderr");
like($lpq_stdout, qr/LIBPQ_STATUS: OK/, 'libpq connection over XPC succeeds');
like($lpq_stdout, qr/LIBPQ_XPC_SERVICE: \Q$svc_name\E/, 'PQxpcService accessor returns service name');
like($lpq_stdout, qr/LIBPQ_ROW: 2 bar/, 'libpq query returns expected row');

$node->stop;

done_testing();
