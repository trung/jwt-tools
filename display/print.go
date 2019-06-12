package display

import (
	"encoding/json"
	"fmt"

	"github.com/tidwall/pretty"
)

func PrintJSON(obj interface{}) error {
	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	jsonStr := pretty.Color(pretty.Pretty(data), nil)
	fmt.Println(string(jsonStr))
	return nil
}
