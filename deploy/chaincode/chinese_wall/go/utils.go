package main

func contains( list []string, a string) bool {
    for _, b := range list {
        if b == a {
            return true
        }
    }
    return false
}
