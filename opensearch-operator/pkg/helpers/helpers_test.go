package helpers

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	opsterv1 "opensearch.opster.io/api/v1"
)

func TestTlsCASecretRef(t *testing.T) {
	tests := []struct {
		name     string
		cluster  *opsterv1.OpenSearchCluster
		expected string
	}{
		{
			name: "returns HTTP caSecret for OpenSearch 2.x",
			cluster: &opsterv1.OpenSearchCluster{
				Spec: opsterv1.ClusterSpec{
					General: opsterv1.GeneralConfig{Version: "2.3.0"},
					Security: &opsterv1.Security{
						Tls: &opsterv1.TlsConfig{
							Http: &opsterv1.TlsConfigHttp{
								TlsCertificateConfig: opsterv1.TlsCertificateConfig{
									CaSecret: corev1.LocalObjectReference{Name: "http-ca"},
								},
							},
						},
					},
				},
			},
			expected: "http-ca",
		},
		{
			name: "returns transport caSecret for OpenSearch 1.x",
			cluster: &opsterv1.OpenSearchCluster{
				Spec: opsterv1.ClusterSpec{
					General: opsterv1.GeneralConfig{Version: "1.3.0"},
					Security: &opsterv1.Security{
						Tls: &opsterv1.TlsConfig{
							Transport: &opsterv1.TlsConfigTransport{
								TlsCertificateConfig: opsterv1.TlsCertificateConfig{
									CaSecret: corev1.LocalObjectReference{Name: "transport-ca"},
								},
							},
						},
					},
				},
			},
			expected: "transport-ca",
		},
		{
			name: "returns empty when TLS is not configured",
			cluster: &opsterv1.OpenSearchCluster{
				Spec: opsterv1.ClusterSpec{
					General: opsterv1.GeneralConfig{Version: "2.3.0"},
				},
			},
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := TlsCASecretRef(test.cluster).Name; got != test.expected {
				t.Fatalf("expected %q, got %q", test.expected, got)
			}
		})
	}
}

func TestSecurityadminCASecretRef(t *testing.T) {
	tests := []struct {
		name     string
		cluster  *opsterv1.OpenSearchCluster
		expected string
	}{
		{
			name: "uses external HTTP certificate secret for OpenSearch 2.x",
			cluster: &opsterv1.OpenSearchCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: opsterv1.ClusterSpec{
					General: opsterv1.GeneralConfig{Version: "2.3.0"},
					Security: &opsterv1.Security{Tls: &opsterv1.TlsConfig{Http: &opsterv1.TlsConfigHttp{
						TlsCertificateConfig: opsterv1.TlsCertificateConfig{
							Secret:   corev1.LocalObjectReference{Name: "http-cert"},
							CaSecret: corev1.LocalObjectReference{Name: "test-ca"},
						},
					}}},
				},
			},
			expected: "http-cert",
		},
		{
			name: "uses generated HTTP certificate secret for OpenSearch 2.x",
			cluster: &opsterv1.OpenSearchCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: opsterv1.ClusterSpec{
					General: opsterv1.GeneralConfig{Version: "2.3.0"},
					Security: &opsterv1.Security{Tls: &opsterv1.TlsConfig{Http: &opsterv1.TlsConfigHttp{
						Generate: true,
						TlsCertificateConfig: opsterv1.TlsCertificateConfig{
							CaSecret: corev1.LocalObjectReference{Name: "test-ca"},
						},
					}}},
				},
			},
			expected: "test-http-cert",
		},
		{
			name: "retains transport caSecret for OpenSearch 1.x",
			cluster: &opsterv1.OpenSearchCluster{
				Spec: opsterv1.ClusterSpec{
					General: opsterv1.GeneralConfig{Version: "1.3.0"},
					Security: &opsterv1.Security{Tls: &opsterv1.TlsConfig{Transport: &opsterv1.TlsConfigTransport{
						TlsCertificateConfig: opsterv1.TlsCertificateConfig{
							Secret:   corev1.LocalObjectReference{Name: "transport-cert"},
							CaSecret: corev1.LocalObjectReference{Name: "transport-ca"},
						},
					}}},
				},
			},
			expected: "transport-ca",
		},
		{
			name: "returns empty when TLS is not configured",
			cluster: &opsterv1.OpenSearchCluster{
				Spec: opsterv1.ClusterSpec{General: opsterv1.GeneralConfig{Version: "2.3.0"}},
			},
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := SecurityadminCASecretRef(test.cluster).Name; got != test.expected {
				t.Fatalf("expected %q, got %q", test.expected, got)
			}
		})
	}
}
