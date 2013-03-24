# == Schema Information
#
# Table name: users
#
#  id         :integer          not null, primary key
#  name       :string(255)
#  email      :string(255)
#  created_at :datetime         not null
#  updated_at :datetime         not null
#

# SHA2 ����������
require 'digest'

class User < ActiveRecord::Base
	# ����������� �������, �� ��������� ������ � ��
	attr_accessor :password
	
	# ������� ��������, ������� ������������� ������ � ��
	attr_accessible :name, :email, :password, :password_confirmation
	
	email_regex = /\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i
	
	validates :name,  		:presence 		=> true,							# ��������� ������� �������� name
							:length   		=> { :maximum => 50 }				# ��������� ����� �������� name
	validates :email, 		:presence 		=> true,							# ��������� ������� �������� email
							:format   		=> { :with => email_regex },		# ��������� ������� �������� email � ������� ����������� ���������
							:uniqueness 	=> { :case_sensitive => false }		# ��������� �������� �������� email �� ������������ (��� ����� �������� ��������)
	validates :password, 	:presence 		=> true,							# ��������� ������� �������� password
							:confirmation 	=> true,							# ��������� ��������� ��������� password � confirmation
							:length 		=> { :within => 6..40 }				# ��������� ����� �������� password
						 
	# �� ���������� �������� encrypt_password ���������� ����� encrypt_password (���������� ��������) 
	before_save :encrypt_password
	
	# ��������� ����� �� ��������� � ����� ������ - ������ �� ��
	def has_password?(submitted_password)
		encrypted_password == encrypt(submitted_password)
	end
	
	# �����, ������������ ���������������� �� ������������, � ������ ������ ������������ ������ user, ��������������� ������� ������������
	def self.authenticate(email, submitted_password)
		user = find_by_email(email)
		return nil if user.nil?
		return user if user.has_password?(submitted_password)
	end
	
	private
	
		def encrypt_password
			self.salt = make_salt if new_record?				# new_record? - ���������� true ���� ������ ��� �� �������� � ��
			self.encrypted_password = encrypt(self.password)
		end
				
		def encrypt(string)
			secure_hash("#{self.salt}--#{string}")
		end
		
		def make_salt
			secure_hash("#{Time.now.utc}--#{password}")
		end
		
		def secure_hash(string)
			Digest::SHA2.hexdigest(string)
		end		
end