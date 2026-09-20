package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
	ErrInvalid  = errors.New("invalid")
)

// Address is one period during which an IP address belonged to a device.
type Address struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	ValidFrom int64  `json:"valid_from,omitempty"` // unix; 0 = since ever
	ValidTo   int64  `json:"valid_to,omitempty"`   // unix; 0 = still current
	Source    string `json:"source"`
}

// Current reports whether the address is assigned right now.
func (a Address) Current() bool { return a.ValidTo == 0 }

type Device struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	Created     int64     `json:"created"`
	Addresses   []Address `json:"addresses"`
}

// CleanName validates a device name: a label for people, so almost anything
// goes — but nothing that breaks a table or a shell pipeline.
func CleanName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return "", fmt.Errorf("%w: a device name must be 1 to 64 characters", ErrInvalid)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%w: a device name cannot contain control characters", ErrInvalid)
		}
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", fmt.Errorf("%w: %q is an IP address — give the device a name", ErrInvalid, name)
	}
	return name, nil
}

// CleanIP normalizes an address the way unbound logs it.
func CleanIP(ip string) (string, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return "", fmt.Errorf("%w: %q is not an IP address", ErrInvalid, ip)
	}
	return a.Unmap().WithZone("").String(), nil
}

func cleanMAC(mac string) (string, error) {
	mac = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(mac), "-", ":"))
	if mac == "" {
		return "", nil
	}
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		return "", fmt.Errorf("%w: %q is not a MAC address", ErrInvalid, mac)
	}
	for _, p := range parts {
		if len(p) != 2 || strings.Trim(p, "0123456789abcdef") != "" {
			return "", fmt.Errorf("%w: %q is not a MAC address", ErrInvalid, mac)
		}
	}
	return mac, nil
}

func (s *Store) deviceID(name string) (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM devices WHERE name = ?`, strings.TrimSpace(name)).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("%w: no device named %q (see `minidns device list`)", ErrNotFound, name)
	}
	return id, err
}

// AddDevice creates a device; addresses are added separately.
func (s *Store) AddDevice(name, description string, tags []string) error {
	name, err := CleanName(name)
	if err != nil {
		return err
	}
	if _, err := s.deviceID(name); err == nil {
		return fmt.Errorf("%w: a device named %q already exists", ErrConflict, name)
	}
	_, err = s.db.Exec(`INSERT INTO devices(name, description, tags, created_at) VALUES (?,?,?,?)`,
		name, strings.TrimSpace(description), strings.Join(tags, ","), time.Now().Unix())
	return err
}

// AddAddress assigns ip to the device from now on — or, when nobody ever
// held that address, for all of recorded history, so that naming a device
// also names its past queries. An address can be current for one device only.
func (s *Store) AddAddress(device, ip, mac, source string) (Address, error) {
	id, err := s.deviceID(device)
	if err != nil {
		return Address{}, err
	}
	if ip, err = CleanIP(ip); err != nil {
		return Address{}, err
	}
	if mac, err = cleanMAC(mac); err != nil {
		return Address{}, err
	}
	if source == "" {
		source = "manual"
	}
	var holder string
	var holderID int64
	err = s.db.QueryRow(`SELECT d.name, d.id FROM device_addresses a JOIN devices d ON d.id = a.device_id WHERE a.ip = ? AND a.valid_to IS NULL`, ip).Scan(&holder, &holderID)
	switch {
	case err == nil && holderID == id:
		return Address{IP: ip, MAC: mac, Source: source}, fmt.Errorf("%w: %s already belongs to %s", ErrConflict, ip, holder)
	case err == nil:
		return Address{}, fmt.Errorf("%w: %s currently belongs to device %q — remove it there first (`minidns device address remove %q %s`)", ErrConflict, ip, holder, holder, ip)
	case err != sql.ErrNoRows:
		return Address{}, err
	}
	var from int64
	s.db.QueryRow(`SELECT COALESCE(MAX(valid_to), 0) FROM device_addresses WHERE ip = ?`, ip).Scan(&from)
	_, err = s.db.Exec(`INSERT INTO device_addresses(device_id, ip, mac, valid_from, source) VALUES (?,?,?,?,?)`, id, ip, mac, from, source)
	return Address{IP: ip, MAC: mac, ValidFrom: from, Source: source}, err
}

// RemoveAddress ends the assignment now: queries the device made from that
// address stay attributed to it. With forget, the assignment is erased as if
// it never existed (for correcting a mistake).
func (s *Store) RemoveAddress(device, ip string, forget bool) error {
	id, err := s.deviceID(device)
	if err != nil {
		return err
	}
	if ip, err = CleanIP(ip); err != nil {
		return err
	}
	var res sql.Result
	if forget {
		res, err = s.db.Exec(`DELETE FROM device_addresses WHERE device_id = ? AND ip = ?`, id, ip)
	} else {
		res, err = s.db.Exec(`UPDATE device_addresses SET valid_to = ? WHERE device_id = ? AND ip = ? AND valid_to IS NULL`, time.Now().Unix(), id, ip)
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %s is not a current address of %s", ErrNotFound, ip, device)
	}
	return nil
}

func (s *Store) RenameDevice(old, new string) error {
	id, err := s.deviceID(old)
	if err != nil {
		return err
	}
	if new, err = CleanName(new); err != nil {
		return err
	}
	if other, err := s.deviceID(new); err == nil && other != id {
		return fmt.Errorf("%w: a device named %q already exists", ErrConflict, new)
	}
	_, err = s.db.Exec(`UPDATE devices SET name = ? WHERE id = ?`, new, id)
	return err
}

// UpdateDevice changes description and/or tags (nil = leave as is).
func (s *Store) UpdateDevice(name string, description *string, tags *[]string) error {
	id, err := s.deviceID(name)
	if err != nil {
		return err
	}
	if description != nil {
		if _, err := s.db.Exec(`UPDATE devices SET description = ? WHERE id = ?`, strings.TrimSpace(*description), id); err != nil {
			return err
		}
	}
	if tags != nil {
		if _, err := s.db.Exec(`UPDATE devices SET tags = ? WHERE id = ?`, strings.Join(*tags, ","), id); err != nil {
			return err
		}
	}
	return nil
}

// RemoveDevice deletes the device and its address history; its queries show
// up under their raw IP addresses again.
func (s *Store) RemoveDevice(name string) error {
	id, err := s.deviceID(name)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`DELETE FROM devices WHERE id = ?`, id)
	return err
}

func (s *Store) Device(name string) (*Device, error) {
	id, err := s.deviceID(name)
	if err != nil {
		return nil, err
	}
	all, err := s.devices(`WHERE d.id = ?`, id)
	if err != nil || len(all) == 0 {
		return nil, err
	}
	return &all[0], nil
}

func (s *Store) Devices() ([]Device, error) { return s.devices(``) }

func (s *Store) devices(where string, args ...any) ([]Device, error) {
	rows, err := s.db.Query(`SELECT d.id, d.name, d.description, d.tags, d.created_at FROM devices d `+where+` ORDER BY d.name COLLATE NOCASE`, args...)
	if err != nil {
		return nil, err
	}
	var out []Device
	var ids []int64
	for rows.Next() {
		var d Device
		var id int64
		var tags string
		if err := rows.Scan(&id, &d.Name, &d.Description, &tags, &d.Created); err != nil {
			rows.Close()
			return nil, err
		}
		if tags != "" {
			d.Tags = strings.Split(tags, ",")
		}
		d.Addresses = []Address{}
		out, ids = append(out, d), append(ids, id)
	}
	rows.Close()
	for i, id := range ids {
		ar, err := s.db.Query(`SELECT ip, mac, valid_from, COALESCE(valid_to, 0), source FROM device_addresses WHERE device_id = ? ORDER BY valid_to IS NOT NULL, valid_from, ip`, id)
		if err != nil {
			return nil, err
		}
		for ar.Next() {
			var a Address
			if err := ar.Scan(&a.IP, &a.MAC, &a.ValidFrom, &a.ValidTo, &a.Source); err != nil {
				ar.Close()
				return nil, err
			}
			out[i].Addresses = append(out[i].Addresses, a)
		}
		ar.Close()
	}
	return out, nil
}

// DeviceAt names the device that held ip at the given time ("" if none).
func (s *Store) DeviceAt(ip string, at int64) string {
	var name string
	s.db.QueryRow(`SELECT d.name FROM device_addresses a JOIN devices d ON d.id = a.device_id
		WHERE a.ip = ? AND a.valid_from <= ? AND (a.valid_to IS NULL OR ? < a.valid_to) LIMIT 1`, ip, at, at).Scan(&name)
	return name
}
