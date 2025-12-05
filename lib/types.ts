export interface ApiResponse<T> {
  statusCode: number;
  message: string;
  data?: T;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  roles: string[];
}

export interface RegistrationRequest {
  name: string;
  email: string;
  password: string;
  roles: string[];
  specialization?: string;
  licenseNumber?: string;
}

export interface User {
  id: number;
  name: string;
  email: string;
  profilePictureUrl?: string;
  roles: Role[];
  doctor?: Doctor;
  patient?: Patient;
  createdAt: string;
  updatedAt: string;
}

export interface Role {
  id: number;
  name: string;
}

export interface Doctor {
  id: number;
  firstName?: string;
  lastName?: string;
  specialization: string;
  licenseNumber: string;
  userId: number;
}

export interface Patient {
  id: number;
  firstName?: string;
  lastName?: string;
  dateOfBirth?: string;
  phone?: string;
  knownAllergies?: string;
  bloodGroup?: string;
  genotype?: string;
  userId: number;
}

export interface UpdatePasswordRequest {
  oldPassword: string;
  newPassword: string;
}

export interface ResetPasswordRequest {
  code: string;
  newPassword: string;
  email?: string;
}
