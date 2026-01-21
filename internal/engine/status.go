package engine

var Version = "dev"

type Status struct {
	ID             string  `json:"id"`
	PID            int     `json:"pid"`
	Version        string  `json:"version"`
	Date           int64   `json:"date"`
	Started        int64   `json:"started"`
	Network        string  `json:"network"`
	PrefixLen      int     `json:"prefixlen"`
	Interface      string  `json:"interface"`
	IP             string  `json:"ip"`
	MAC            string  `json:"mac"`
	QueueDepth     int     `json:"queue_depth"`
	MaxRate        float64 `json:"max_rate"`
	FloodProtect   float64 `json:"flood_protection"`
	MaxPending     int     `json:"max_pending"`
	SweepPeriod    int     `json:"sweep_period"`
	SweepAge       int     `json:"sweep_age"`
	SweepSkipAlive bool    `json:"sweep_skip_alive"`
	Proberate      float64 `json:"proberate"`
	NextSweep      int64   `json:"next_sweep"`
	LearningLeft   int     `json:"learning"`
	Dummy          bool    `json:"dummy"`
	Passive        bool    `json:"passive"`
	Static         bool    `json:"static"`
	SpongeNet      bool    `json:"sponge_network"`
}

type IPState struct {
	IP         string  `json:"ip"`
	State      string  `json:"state"`
	Queue      int     `json:"queue"`
	Rate       float64 `json:"rate"`
	StateMTime int64   `json:"state_mtime"`
	StateATime int64   `json:"state_atime"`
}

type ARPState struct {
	IP   string `json:"ip"`
	MAC  string `json:"mac"`
	Time int64  `json:"time"`
}
