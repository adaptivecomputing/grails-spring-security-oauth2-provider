package test

class Role {

	String authority

	static mapping = {
		autoImport false
		table 'test_role'
		cache true
	}

	static constraints = {
		authority blank: false, unique: true
	}
}
