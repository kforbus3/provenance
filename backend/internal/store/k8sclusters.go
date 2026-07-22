package store

import (
	"context"

	"github.com/google/uuid"
)

// K8sCluster is a registered Kubernetes cluster target for brokered access.
type K8sCluster struct {
	ID             uuid.UUID  `json:"id"`
	Name           string     `json:"name"`
	APIServer      string     `json:"apiServer"`
	CredentialID   *uuid.UUID `json:"credentialId"`
	CredentialName string     `json:"credentialName"`
	CACert         string     `json:"-"` // never serialized to the client
	InsecureTLS    bool       `json:"insecureTls"`
	Namespace      string     `json:"namespace"`
	Description    string     `json:"description"`
	CreatedByName  string     `json:"createdBy"`
	CreatedAt      string     `json:"createdAt"`
	UpdatedAt      string     `json:"updatedAt"`
}

const k8sCols = `c.id, c.name, c.api_server, c.credential_id, COALESCE(s.name,''),
	c.ca_cert, c.insecure_tls, c.namespace, c.description, COALESCE(u.username,''),
	c.created_at::text, c.updated_at::text`

const k8sFrom = `FROM k8s_clusters c
	LEFT JOIN vault_secrets s ON s.id = c.credential_id
	LEFT JOIN users u ON u.id = c.created_by`

func scanK8sCluster(row interface{ Scan(...any) error }) (*K8sCluster, error) {
	var c K8sCluster
	if err := row.Scan(&c.ID, &c.Name, &c.APIServer, &c.CredentialID, &c.CredentialName,
		&c.CACert, &c.InsecureTLS, &c.Namespace, &c.Description, &c.CreatedByName,
		&c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) ListK8sClusters(ctx context.Context) ([]K8sCluster, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+k8sCols+` `+k8sFrom+` ORDER BY c.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []K8sCluster
	for rows.Next() {
		c, err := scanK8sCluster(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func (s *Store) GetK8sCluster(ctx context.Context, id uuid.UUID) (*K8sCluster, error) {
	return scanK8sCluster(s.pool.QueryRow(ctx, `SELECT `+k8sCols+` `+k8sFrom+` WHERE c.id=$1`, id))
}

// K8sClusterInput is the payload to create or update a cluster.
type K8sClusterInput struct {
	Name         string
	APIServer    string
	CredentialID *uuid.UUID
	CACert       string
	InsecureTLS  bool
	Namespace    string
	Description  string
	CreatedBy    uuid.UUID
}

func (s *Store) CreateK8sCluster(ctx context.Context, in K8sClusterInput) (*K8sCluster, error) {
	var id uuid.UUID
	if err := s.pool.QueryRow(ctx, `
		INSERT INTO k8s_clusters (name, api_server, credential_id, ca_cert, insecure_tls, namespace, description, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		in.Name, in.APIServer, in.CredentialID, in.CACert, in.InsecureTLS, in.Namespace, in.Description, in.CreatedBy).Scan(&id); err != nil {
		return nil, err
	}
	return s.GetK8sCluster(ctx, id)
}

func (s *Store) UpdateK8sCluster(ctx context.Context, id uuid.UUID, in K8sClusterInput) (*K8sCluster, error) {
	if _, err := s.pool.Exec(ctx, `
		UPDATE k8s_clusters SET name=$2, api_server=$3, credential_id=$4, ca_cert=$5,
			insecure_tls=$6, namespace=$7, description=$8, updated_at=now()
		WHERE id=$1`,
		id, in.Name, in.APIServer, in.CredentialID, in.CACert, in.InsecureTLS, in.Namespace, in.Description); err != nil {
		return nil, err
	}
	return s.GetK8sCluster(ctx, id)
}

func (s *Store) DeleteK8sCluster(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM k8s_clusters WHERE id=$1`, id)
	return err
}
